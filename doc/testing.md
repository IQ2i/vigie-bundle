# Testing

`IQ2i\VigieBundle\Test` lets an application test its own code against vigie — "did this request record that
activity?" — without a database and without depending on the bundle's internals.

```yaml
# config/packages/test/vigie.yaml
iq2i_vigie:
    storage: in_memory
```

The bundle registers a single shared `InMemoryActivityStorage` instance, aliased onto
`IQ2i\VigieBundle\Storage\InMemoryActivityStorage` so it can be fetched from the container in a test — see
[doc/configuration.md](configuration.md) for the other ways to wire `storage`.

```php
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Test\VigieAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class LoginTest extends WebTestCase
{
    use VigieAssertionsTrait;

    public function testAFailedLoginIsRecorded(): void
    {
        $client = static::createClient();
        $client->request('POST', '/login', ['username' => 'jane.doe', 'password' => 'wrong']);

        /** @var InMemoryActivityStorage $storage */
        $storage = static::getContainer()->get(InMemoryActivityStorage::class);

        self::assertActivityRecorded($storage, ActivityType::LoginFailure);
    }
}
```

`InMemoryActivityStorage` is a plain, mutable, process-local collection — nothing is persisted, nothing is
shared between test methods unless you explicitly reuse the same instance (or, in a functional test, the
same booted kernel).

`VigieAssertionsTrait` requires `phpunit/phpunit` and delegates statically to `PHPUnit\Framework\Assert`, so
it works from any test case (or none) across PHPUnit 10, 11 and 12:

```php
// $matcher: an ActivityType matches on $activity->type; a callable(Activity): bool matches on anything else.
// $message overrides the default failure message, like any other PHPUnit assertion.
assertActivityRecorded(InMemoryActivityStorage $storage, callable|ActivityType $matcher, string $message = ''): void
assertActivityNotRecorded(InMemoryActivityStorage $storage, callable|ActivityType $matcher, string $message = ''): void
assertActivityCount(InMemoryActivityStorage $storage, int $expectedCount, ?callable $matcher = null, string $message = ''): void
```
