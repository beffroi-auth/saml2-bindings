<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function array_any;
use function array_filter;
use function array_keys;
use function dirname;
use function file_get_contents;
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
use function strtolower;
use function substr;
use function substr_count;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_ENCAPSED_AND_WHITESPACE;
use const T_SPACESHIP;

/**
 * Section 8 of spec/bindings.md, read on the source of src/ itself, next to the PHPStan rules of
 * .ci-tools/phpstan.neon, as saml2-model reads its own: what PHPStan cannot see. The property reads Core's Text::of()
 * replaces (textContent, nodeValue, innerHTML), and the comparison <=>. Comments and string literals are not code and
 * are not scanned: a refusal message may name what it refuses.
 *
 * Section 8, I-12.
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
