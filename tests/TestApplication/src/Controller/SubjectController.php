<?php

declare(strict_types=1);

/*
 * This file is part of the Vigie Bundle.
 *
 * (c) Loïc Sapone <loic@sapone.fr>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace IQ2i\VigieBundle\Tests\TestApplication\Controller;

use IQ2i\VigieBundle\Attribute\Track;
use Symfony\Component\HttpFoundation\Response;

/**
 * Exercises #[Track(subject:)] end to end; ConfigurationTest asserts the
 * recorded activity's subject_type/subject_id come out of the route's "id".
 */
#[Track('subject.show', subject: 'thing')]
final class SubjectController
{
    public function __invoke(): Response
    {
        return new Response('subject');
    }
}
