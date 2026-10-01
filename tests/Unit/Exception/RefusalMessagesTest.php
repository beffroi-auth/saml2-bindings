<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Exception;

use function array_filter;
use function array_map;
use function array_values;
use function basename;
use function dirname;
use function file_get_contents;
use function glob;
use function in_array;
use function ltrim;
use PhpToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_match;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SensitiveParameter;
use SplFileInfo;
use function sprintf;
use function strlen;
use function strrchr;
use function substr;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_NEW;

/**
 * §9.3 row 14, B-11: every message of an exception of src/, read on the source, ends with the rule that refused, in
 * parentheses, and is written in the code, a literal or the format of a sprintf() whose arguments are names and bounds,
 * never a value of the input. The exceptions read are the BindingRefused subclasses of src/Exception/ and the
 * programming errors of the caller (section 5.4, \InvalidArgumentException and \LogicException), since B-11 holds for
 * every exception the package throws. That no message carries a value of the input is asserted by every refusal test.
 */
final class RefusalMessagesTest extends TestCase
{
    /**
     * The programming errors of the caller the package throws (section 5.4).
     */
    private const array PROGRAMMING_ERRORS = ['InvalidArgumentException', 'LogicException'];

    /**
     * §9.3 row 14, B-11: the message of every exception src/ throws ends with "(B-n)." or "(section n).".
     */
    #[Test]
    public function everyRefusalNamesItsRule(): void
    {
        // Given
        $messages = [];
        foreach ($this->sources() as $file => $source) {
            foreach ($this->messages($source) as $message) {
                $messages[] = [$file, $message];
            }
        }

        // When
        $unnamed = array_values(array_filter(
            $messages,
            static fn (array $message): bool => ! self::namesItsRule($message[1]),
        ));

        // Then
        static::assertNotSame([], $messages);
        static::assertSame([], array_map(static fn (array $message): string => sprintf(
            '%s: %s',
            $message[0],
            $message[1],
        ), $unnamed));
    }

    /**
     * B-11: the rule a message ends with, and what does not count as one.
     */
    #[Test]
    #[TestWith(['A query string carries both message parameters (B-1).', true], 'an invariant')]
    #[TestWith(['A SAMLEncoding other than DEFLATE is refused (section 8).', true], 'a section')]
    #[TestWith(['maxInflatedBytes must be between 1 and 1048576 (section 7).', true], 'a bound')]
    #[TestWith(['The RelayState changed after signing (B-2, B-9).', true], 'two invariants')]
    #[TestWith(['A query string carries both message parameters (B-1)', false], 'no final period')]
    #[TestWith(['A query string carries both message parameters.', false], 'no rule')]
    #[TestWith(['The signature does not verify (D-5).', false], 'a rule of another package')]
    #[TestWith(['The RelayState is too long (B-9): refused.', false], 'a rule in the middle')]
    public function itReadsTheRuleAMessageEndsWith(string $message, bool $named): void
    {
        // When / Then
        static::assertSame($named, self::namesItsRule($message));
    }

    /**
     * The scan finds the messages of an exception, built as the source builds them, and marks one it cannot read.
     *
     * @param list<string> $expected
     */
    #[Test]
    #[TestWith([
        "<?php throw new MalformedParameters('A query string carries both message parameters (B-1).');",
        ['A query string carries both message parameters (B-1).'],
    ], 'a literal')]
    #[TestWith([
        "<?php throw new LimitExceeded(sprintf('The query string is over %s (B-7).', 'maxQueryStringBytes'));",
        ['The query string is over %s (B-7).'],
    ], 'a format')]
    #[TestWith([
        "<?php throw new Exception\\MalformedEncoding('A percent-escape is malformed (B-8).');",
        ['A percent-escape is malformed (B-8).'],
    ], 'a qualified name')]
    #[TestWith([
        "<?php throw new \\InvalidArgumentException('The RelayState is empty (B-9).');",
        ['The RelayState is empty (B-9).'],
    ], 'a programming error')]
    #[TestWith(["<?php throw new InvalidRelayState(\$message);", ['<not a literal>']], 'a variable')]
    #[TestWith(["<?php throw new RuntimeException('Not ours.');", []], 'another exception')]
    public function itFindsTheMessagesOfAnException(string $source, array $expected): void
    {
        // When / Then
        static::assertSame($expected, $this->messages($source));
    }

    private static function namesItsRule(string $message): bool
    {
        return (
            preg_match('~\((?:B-\d+|section \d+(?:\.\d+)*)(?:, (?:B-\d+|section \d+(?:\.\d+)*))*\)\.\z~', $message)
            === 1
        );
    }

    /**
     * The messages the source gives an exception: the first argument of new <BindingRefused subclass>(...) or new
     * <programming error>(...), a literal or the format of sprintf(); anything else is "<not a literal>".
     *
     * @return list<string>
     */
    private function messages(string $source): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn (#[SensitiveParameter] PhpToken $phpToken): bool => ! $phpToken->isIgnorable(),
        ));
        $exceptions = [...$this->refusals(), ...self::PROGRAMMING_ERRORS];
        $messages = [];
        foreach ($tokens as $index => $token) {
            if (
                ! $token->is(T_NEW) || ! in_array($this->shortName($tokens[$index + 1]->text ?? ''), $exceptions, true)
            ) {
                continue;
            }
            $messages[] = $this->argument($tokens, $index + 3);
        }

        return $messages;
    }

    /**
     * The last segment of a class name as written: InvalidArgumentException of \InvalidArgumentException,
     * MalformedEncoding of Exception\MalformedEncoding.
     */
    private function shortName(string $name): string
    {
        $last = strrchr($name, '\\');

        return $last === false ? $name : ltrim($last, '\\');
    }

    /**
     * The message at $index, the first token of an argument: a literal, or the literal format of sprintf().
     *
     * @param list<PhpToken> $tokens
     */
    private function argument(array $tokens, int $index): string
    {
        $token = $tokens[$index] ?? null;
        if ($token?->text === 'sprintf') {
            $token = $tokens[$index + 2] ?? null;
        }

        return $token?->is(T_CONSTANT_ENCAPSED_STRING) === true ? $this->unquote($token->text) : '<not a literal>';
    }

    private function unquote(string $literal): string
    {
        return substr($literal, 1, strlen($literal) - 2);
    }

    /**
     * The short names of the BindingRefused subclasses, the files of src/Exception/ but their base class.
     *
     * @return list<string>
     */
    private function refusals(): array
    {
        $files = glob(dirname(__DIR__, 3) . '/src/Exception/*.php');
        static::assertIsArray($files);

        return array_values(array_filter(
            array_map(static fn (string $file): string => basename($file, '.php'), $files),
            static fn (string $name): bool => $name !== 'BindingRefused',
        ));
    }

    /**
     * @return array<string, string> each PHP file of src/, its path relative to src/ to its source
     */
    private function sources(): array
    {
        $directory = dirname(__DIR__, 3) . '/src';
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

        return $sources;
    }
}
