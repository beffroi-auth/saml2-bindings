<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\PhpStan;

use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FunctionCallableNode;
use PHPStan\Node\MethodCallableNode;
use PHPStan\Node\StaticMethodCallableNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;

/**
 * Section 8 of the specification: a first-class callable of a banned or a confined call, base64_decode(...) handed to
 * array_map() or time(...) kept for later, is the call it is made of. PHPStan visits it as a node of its own and never
 * as that call, so BannedCallsRule would not see it: this rule hands it the call. One service per kind of callable, the
 * function, the method and the static method, each named by its node type in .ci-tools/phpstan.neon.
 *
 * @template TNode of FunctionCallableNode|MethodCallableNode|StaticMethodCallableNode
 *
 * @implements Rule<TNode>
 */
final readonly class BannedCallablesRule implements Rule
{
    /**
     * @param class-string<TNode> $nodeType
     */
    public function __construct(
        private BannedCallsRule $calls,
        private string $nodeType,
    ) {
    }

    public function getNodeType(): string
    {
        return $this->nodeType;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        return $this->calls->processNode($node->getOriginalNode(), $scope);
    }
}
