<?php

namespace Lazorkit\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Cache\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class LazorkitRateLimiter
{
    protected RateLimiter $limiter;

    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $key = $this->resolveRequestKey($request);
        $maxAttempts = $this->getMaxAttempts($request);

        if ($this->limiter->tooManyAttempts($key, $maxAttempts)) {
            return response()->json([
                'error' => 'Too many requests. Please try again later.',
                'retry_after' => $this->limiter->availableIn($key),
            ], 429);
        }

        $this->limiter->hit($key, 60); // 1 minute decay

        $response = $next($request);

        return $this->addRateLimitHeaders(
            $response,
            $maxAttempts,
            $this->limiter->remaining($key, $maxAttempts)
        );
    }

    /**
     * Resolve the request key for rate limiting.
     */
    protected function resolveRequestKey(Request $request): string
    {
        $identifier = $request->ip();

        // Use wallet address if authenticated
        if ($walletAddress = session('wallet_address')) {
            $identifier = $walletAddress;
        }

        return 'lazorkit:' . $request->route()->getName() . ':' . $identifier;
    }

    /**
     * Get max attempts based on route type.
     */
    protected function getMaxAttempts(Request $request): int
    {
        $routeName = $request->route()->getName();

        // Transaction endpoints have stricter limits
        if (str_contains($routeName, 'transaction')) {
            return config('lazorkit.rate_limits.transaction', 5);
        }

        // Auth endpoints
        return config('lazorkit.rate_limits.auth', 10);
    }

    /**
     * Add rate limit headers to response.
     */
    protected function addRateLimitHeaders(Response $response, int $maxAttempts, int $remainingAttempts): Response
    {
        $response->headers->set('X-RateLimit-Limit', $maxAttempts);
        $response->headers->set('X-RateLimit-Remaining', max(0, $remainingAttempts));

        return $response;
    }
}
