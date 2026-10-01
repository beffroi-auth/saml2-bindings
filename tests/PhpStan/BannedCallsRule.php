<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\PhpStan;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use function array_any;
use function implode;
use function rtrim;
use function sprintf;
use function str_ends_with;
use function str_starts_with;
use function strtolower;

/**
 * Section 8 of the specification: the methods of the Dom API and the functions never called, as saml2-model bans them
 * (model.md section 8), in src/ and in tests/; and the calls section 8 confines to named files, as xml-security
 * confines createFromString() to its Loader: the percent codec to Internal\Percent, base64_decode() to Internal\Base64,
 * inflation to Internal\Inflater, deflation to Internal\Deflater, validateAuthenticatedByBinding() to the four Received*
 * classes (B-5, B-8). base64_decode() is called with its strict flag wherever it is allowed (B-8).
 *
 * A function name ending with * bans the prefix (every openssl_* function). A method of a class of the SAML stack is
 * not the Dom method of the same name (AuthnRequestValidator::validate() of the model, ReceivedAuthnRequest::validate()
 * of this package, are not Dom\Document::validate()), so a call to a banned method whose receiver is known to be one
 * is let through; a confined method is confined whatever its receiver. A dynamic call or a dynamic instantiation would
 * escape the rule, so both are refused too; a first-class callable of a banned or confined call (base64_decode(...)
 * handed to array_map()), which PHPStan visits as a node of its own, is BannedCallablesRule's, which asks this rule.
 * ekino/phpstan-banned-code bans a function by the name as written; this rule reads the name as resolved, whatever its
 * case.
 *
 * @implements Rule<CallLike>
 */
final class BannedCallsRule implements Rule
{
    /**
     * The namespaces of the SAML stack, lowercased: this package's and the model's.
     */
    private const array STACK = ['beffroi\\saml2\\bindings\\', 'beffroi\\saml2\\model\\'];

    /**
     * @var array<string, string> the lowercased method names, mapped to the spelling of the configuration
     */
    private array $methods = [];

    /**
     * @var array<string, string> the lowercased function names, mapped to the spelling of the configuration
     */
    private array $functions = [];

    /**
     * @var array<string, string> the lowercased function prefixes, mapped to the spelling of the configuration
     */
    private array $prefixes = [];

    /**
     * @var array<string, array{spelling: string, allowedIn: list<string>}> keyed by the lowercased method name
     */
    private array $confinedMethods = [];

    /**
     * @var array<string, array{spelling: string, allowedIn: list<string>}> keyed by the lowercased function name
     */
    private array $confinedFunctions = [];

    /**
     * @param list<string>                                                                $methods
     * @param list<string>                                                                $functions each a name, or a prefix followed by *
     * @param list<array{method?: string, function?: string, allowedIn: list<string>}> $confined  one of method or function each, its paths relative to the working directory
     */
    public function __construct(
        array $methods,
        array $functions,
        array $confined,
        private readonly string $workingDirectory,
    ) {
        foreach ($methods as $method) {
            $this->methods[strtolower($method)] = $method;
        }
        foreach ($functions as $function) {
            if (str_ends_with($function, '*')) {
                $this->prefixes[strtolower(rtrim($function, '*'))] = $function;
                continue;
            }
            $this->functions[strtolower($function)] = $function;
        }
        foreach ($confined as $call) {
            if (($call['function'] ?? null) !== null) {
                $this->confinedFunctions[strtolower($call['function'])] = [
                    'spelling' => $call['function'],
                    'allowedIn' => $call['allowedIn'],
                ];
                continue;
            }
            if (($call['method'] ?? null) !== null) {
                $this->confinedMethods[strtolower($call['method'])] = [
                    'spelling' => $call['method'],
                    'allowedIn' => $call['allowedIn'],
                ];
            }
        }
    }

    public function getNodeType(): string
    {
        return CallLike::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if ($node instanceof New_) {
            return (
                $node->class instanceof Name || $node->class instanceof Class_
                    ? []
                    : [$this->error('A dynamic instantiation escapes the review: name the class.')]
            );
        }
        if ($node instanceof FuncCall) {
            if (! $node->name instanceof Name) {
                return [$this->error('A dynamic call escapes the review: name the function.')];
            }

            return [
                ...$this->banned($this->function($node->name)),
                ...$this->confined($this->confinedFunctions[$node->name->toLowerString()] ?? null, $scope),
                ...$this->strict($node, $scope),
            ];
        }
        if (! $node instanceof MethodCall && ! $node instanceof NullsafeMethodCall && ! $node instanceof StaticCall) {
            return [];
        }
        if (! $node->name instanceof Identifier) {
            return [$this->error('A dynamic call escapes the review: name the method.')];
        }
        $confined = $this->confined($this->confinedMethods[$node->name->toLowerString()] ?? null, $scope);
        $method = $this->methods[$node->name->toLowerString()] ?? null;
        if ($method === null || $this->ofTheStack($node, $scope)) {
            return $confined;
        }

        return [...$this->banned($method . '()'), ...$confined];
    }

    /**
     * The banned function $name calls, as the configuration spells it or, for a banned prefix, as written; else null.
     */
    private function function(Name $name): ?string
    {
        $function = $this->functions[$name->toLowerString()] ?? null;
        if ($function !== null) {
            return $function . '()';
        }
        foreach ($this->prefixes as $prefix => $spelling) {
            if (str_starts_with($name->toLowerString(), $prefix)) {
                return sprintf('%s(), of %s,', $name->toString(), $spelling);
            }
        }

        return null;
    }

    /**
     * Whether the receiver of the call is a class of the SAML stack, as far as PHPStan knows its type.
     */
    private function ofTheStack(MethodCall|NullsafeMethodCall|StaticCall $node, Scope $scope): bool
    {
        if ($node instanceof StaticCall) {
            return $node->class instanceof Name && $this->inTheStack($scope->resolveName($node->class));
        }

        return array_any($scope->getType($node->var)->getObjectClassNames(), $this->inTheStack(...));
    }

    private function inTheStack(string $class): bool
    {
        return array_any(
            self::STACK,
            static fn (string $namespace): bool => str_starts_with(strtolower($class), $namespace),
        );
    }

    /**
     * @return list<IdentifierRuleError>
     */
    private function banned(?string $call): array
    {
        if ($call === null) {
            return [];
        }

        return [$this->error(sprintf('%s is never called: section 8 of the specification bans it.', $call))];
    }

    /**
     * @param ?array{spelling: string, allowedIn: list<string>} $call
     *
     * @return list<IdentifierRuleError>
     */
    private function confined(?array $call, Scope $scope): array
    {
        if ($call === null) {
            return [];
        }
        foreach ($call['allowedIn'] as $path) {
            if (str_starts_with($scope->getFile(), $this->workingDirectory . '/' . $path)) {
                return [];
            }
        }

        return [
            $this->error(
                $call['allowedIn'] === []
                    ? sprintf('%s() is never called: section 8 of the specification bans it.', $call['spelling'])
                    : sprintf(
                        '%s() is called in %s only: section 8 of the specification confines it there.',
                        $call['spelling'],
                        implode(', ', $call['allowedIn']),
                    ),
            ),
        ];
    }

    /**
     * B-8: base64_decode() with its strict flag, true as PHPStan knows it, positional or named; a first-class callable
     * of it has no flag and is refused too.
     *
     * @return list<IdentifierRuleError>
     */
    private function strict(FuncCall $node, Scope $scope): array
    {
        if (! $node->name instanceof Name || $node->name->toLowerString() !== 'base64_decode') {
            return [];
        }
        $flag = null;
        if (! $node->isFirstClassCallable()) {
            foreach ($node->getArgs() as $position => $argument) {
                if ($argument->name === null ? $position !== 1 : $argument->name->toString() !== 'strict') {
                    continue;
                }
                $flag = $argument;
            }
        }
        if ($flag instanceof Arg && ! $flag->unpack && $scope->getType($flag->value)->isTrue()->yes()) {
            return [];
        }

        return [
            $this->error('base64_decode() without its strict flag, true, is never called: section 8 of the specification bans it.'),
        ];
    }

    private function error(string $message): IdentifierRuleError
    {
        return RuleErrorBuilder::message($message)->identifier('beffroi.bannedCall')->nonIgnorable()->build();
    }
}
