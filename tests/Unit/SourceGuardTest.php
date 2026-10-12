<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function array_any;
use function array_filter;
use function array_keys;
use function dirname;
use function file_get_contents;
use function in_array;
use function ltrim;
use function ksort;
use PhpToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SensitiveParameter;
use SplFileInfo;
use function sprintf;
use function str_contains;
use function strlen;
use function str_starts_with;
use function strtolower;
use function substr;
use function substr_count;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_ECHO;
use const T_ENCAPSED_AND_WHITESPACE;
use const T_INLINE_HTML;
use const T_NAME_FULLY_QUALIFIED;
use const T_NAME_QUALIFIED;
use const T_PRINT;
use const T_SPACESHIP;
use const T_STRING;
use const T_VARIABLE;

/**
 * Section 8 of spec/bindings.md, read on the source of src/ itself, next to the PHPStan rules of
 * .ci-tools/phpstan.neon, as saml2-model reads its own: what PHPStan cannot see. The property reads Core's Text::of()
 * replaces (textContent, nodeValue, innerHTML), and the comparison <=>; and, next to Deptrac, what would reach HTTP.
 * Comments and string literals are not code and are not scanned: a refusal message may name what it refuses.
 *
 * Section 8, I-12, B-13.
 */
final class SourceGuardTest extends TestCase
{
    /**
     * Section 8, I-12: never written in src/, whatever the case.
     */
    #[Test]
    #[DataProvider('provideBannedTokens')]
    public function itNeverWritesABannedToken(string $banned): void
    {
        // When
        $occurrences = $this->occurrences($banned);

        // Then
        static::assertSame([], $occurrences, sprintf('"%s" is banned by section 8 of the specification.', $banned));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBannedTokens(): iterable
    {
        // the property reads Text::of() replaces (I-12): the package reads no SAML element, and looks for one node
        // only, with Children::optional() (B-6)
        yield 'textContent' => ['textContent'];
        yield 'nodeValue' => ['nodeValue'];
        yield 'innerHTML' => ['innerHTML'];
    }

    /**
     * Section 8: no comparison <=>, which orders values of any type with PHP's own rules.
     */
    #[Test]
    public function itNeverComparesWithTheSpaceship(): void
    {
        // When
        $files = array_keys(array_filter($this->sources(), $this->hasSpaceship(...)));

        // Then
        static::assertSame([], $files);
    }

    /**
     * The scans find what they look for in the code, and nothing in a comment or a string literal.
     */
    #[Test]
    #[TestWith(['<?php return $a <=> $b;', true, false], 'a spaceship')]
    #[TestWith(["<?php return '\$a <=> \$b';", false, false], 'a spaceship in a string')]
    #[TestWith(['<?php return $node->textContent;', false, true], 'a property read')]
    #[TestWith(['<?php return $node->TEXTCONTENT;', false, true], 'a property read in another case')]
    #[TestWith(["<?php // \$node->textContent\nreturn \$node;", false, false], 'a property read in a comment')]
    #[TestWith(["<?php return 'textContent';", false, false], 'a property name in a string')]
    #[TestWith(['<?php return "a $b textContent";', false, false], 'a property name in an interpolated string')]
    public function itFindsWhatItScansFor(string $source, bool $spaceship, bool $textContent): void
    {
        // When / Then
        static::assertSame(
            [$spaceship, $textContent],
            [$this->hasSpaceship($source), str_contains($this->code($source), 'textcontent')],
        );
    }

    /**
     * B-13, section 8, decisions 0007 and 0013: src/ names no class of HttpFoundation or of PSR-7, reads no superglobal,
     * sends no header and no cookie, and writes no output and no HTML, so that the package takes strings and arrays and
     * gives back strings and value objects; read on the tokens of the source, next to what Deptrac and the PHPStan
     * rules hold.
     */
    #[Test]
    public function itNeverReachesHttp(): void
    {
        // When
        $files = array_keys(array_filter($this->sources(), $this->reachesHttp(...)));

        // Then
        static::assertSame([], $files);
    }

    /**
     * B-13: the scan of HTTP finds it in the code, and nothing in a comment, a string literal or a name it only
     * resembles.
     */
    #[Test]
    #[TestWith(['<?php return $_GET;', true], 'a superglobal')]
    #[TestWith(
        ['<?php return $_server;', false],
        'a variable named as a superglobal in another case, which PHP tells apart',
    )]
    #[TestWith(["<?php \\HEADER('Location: /');", true], 'a header in another case, which PHP does not tell apart')]
    #[TestWith(["<?php return \$GLOBALS['_POST'];", true], 'a superglobal through GLOBALS')]
    #[TestWith(['<?php use Symfony\\Component\\HttpFoundation\\Request;', true], 'HttpFoundation')]
    #[TestWith(['<?php function f(\\Psr\\Http\\Message\\ServerRequestInterface $r): void {}', true], 'PSR-7')]
    #[TestWith(["<?php header('Location: /');", true], 'a header')]
    #[TestWith(["<?php \\setcookie('a', 'b');", true], 'a cookie')]
    #[TestWith(['<?php echo 1;', true], 'an output')]
    #[TestWith(['<?php print 1;', true], 'a print')]
    #[TestWith(['<p><?php return 1;', true], 'inline HTML')]
    #[TestWith(["<?php return '\$_GET';", false], 'a superglobal in a string')]
    #[TestWith(["<?php // header('Location: /')\nreturn 1;", false], 'a header in a comment')]
    #[TestWith(["<?php return sprintf('%s', 1);", false], 'a function whose name holds print')]
    #[TestWith(['<?php return $_GETTER;', false], 'a variable whose name begins as a superglobal')]
    public function itFindsHttpWhereItIs(string $source, bool $reaches): void
    {
        // When / Then
        static::assertSame($reaches, $this->reachesHttp($source));
    }

    private function reachesHttp(string $source): bool
    {
        return array_any(PhpToken::tokenize($source), static fn (
            #[SensitiveParameter]
            PhpToken $token,
        ): bool => match (true) {
            $token->is([T_ECHO, T_PRINT, T_INLINE_HTML]) => true,
            $token->is(T_VARIABLE) => in_array(
                $token->text,
                [
                    '$_GET',
                    '$_POST',
                    '$_REQUEST',
                    '$_SERVER',
                    '$_COOKIE',
                    '$_FILES',
                    '$_ENV',
                    '$GLOBALS',
                ],
                true,
            ),
            $token->is([T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED]) => str_contains(
                strtolower($token->text),
                'httpfoundation',
            )
                || str_starts_with(strtolower(ltrim($token->text, '\\')), 'psr\\http\\')
                || in_array(
                    strtolower(ltrim($token->text, '\\')),
                    [
                        'header',
                        'header_remove',
                        'headers_list',
                        'http_response_code',
                        'setcookie',
                        'setrawcookie',
                    ],
                    true,
                ),
            default => false,
        });
    }

    private function hasSpaceship(string $source): bool
    {
        return array_any(PhpToken::tokenize($source), static fn (
            #[SensitiveParameter]
            PhpToken $token,
        ): bool => $token->is(T_SPACESHIP));
    }

    /**
     * The code of $source, lowercased, its comments, whitespace and string literals each replaced by a space.
     */
    private function code(string $source): string
    {
        $code = '';
        foreach (PhpToken::tokenize($source) as $phpToken) {
            $code .= $phpToken->isIgnorable() || $phpToken->is([T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE])
                ? ' '
                : $phpToken->text;
        }

        return strtolower($code);
    }

    /**
     * The files of src/ holding $banned in their code, comments and string literals left aside, each with its count.
     *
     * @return array<string, int>
     */
    private function occurrences(string $banned): array
    {
        $occurrences = [];
        foreach ($this->sources() as $path => $source) {
            $count = substr_count($this->code($source), strtolower($banned));
            if ($count > 0) {
                $occurrences[$path] = $count;
            }
        }
        ksort($occurrences);

        return $occurrences;
    }

    /**
     * @return array<string, string> the source of every PHP file of src/, keyed by its path relative to src/
     */
    private function sources(): array
    {
        $directory = dirname(__DIR__, 2) . '/src';
        $sources = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            static::assertIsString($source);
            $sources[substr($file->getPathname(), strlen($directory) + 1)] = $source;
        }
        static::assertNotSame([], $sources);

        return $sources;
    }
}
