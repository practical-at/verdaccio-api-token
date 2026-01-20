import { Logger } from '@verdaccio/types';

interface ApiTokenAuthConfig {
    endpoint: string;
    signupUrl?: string;
    timeout?: number;
}

interface VerdaccioStuff {
    logger: Logger;
}

interface ApiResponse {
    valid?: boolean;
    username?: string;
    groups?: string[];
}

type AuthCallback = (err: Error | null, groups?: string[] | false) => void;
type AllowCallback = (err: Error | null, allowed?: boolean) => void;

interface RemoteUser {
    name: string;
    groups: string[];
    real_groups: string[];
}

interface PackageAccess {
    name: string;
    publish?: string[] | string;
    unpublish?: string[] | string;
    [key: string]: any;
}

interface AuthPlugin {
    authenticate(user: string, password: string, cb: AuthCallback): void;
    add_user(user: string, password: string, cb: AuthCallback): void;
    allow_publish(user: RemoteUser, pkg: PackageAccess, cb: AllowCallback): void;
    allow_unpublish(user: RemoteUser, pkg: PackageAccess, cb: AllowCallback): void;
    apiJWTmiddleware(): (
        req: any,
        res: any,
        next: (err?: any) => void
    ) => Promise<void>;
}

interface CachedUser {
    username: string;
    groups: string[];
}

export = function apiTokenAuth(
    config: ApiTokenAuthConfig,
    stuff: VerdaccioStuff
): AuthPlugin {
    const logger = stuff.logger;
    const endpoint = config.endpoint;
    const signupUrl = config.signupUrl || 'your signup page';
    const timeout = config.timeout ?? 5000;

    // Cache validated tokens with their user data for performance
    // Tokens are removed from cache when validation fails on subsequent requests
    const validatedTokens = new Map<string, CachedUser>();

    if (!endpoint) {
        logger.error('verdaccio-api-token: "endpoint" missing');
        return {
            authenticate(user, password, cb) {
                cb(null, false);
            },
            add_user(user, password, cb) {
                cb(null, false);
            },
            allow_publish(user, pkg, cb) {
                cb(null, false);
            },
            allow_unpublish(user, pkg, cb) {
                cb(null, false);
            },
            apiJWTmiddleware() {
                return async (_req, _res, next) => next();
            },
        };
    }

    /**
     * Validates a token by calling the configured API endpoint
     * @param token - The token to validate
     * @returns ApiResponse if valid, null if invalid or error occurred
     */
    async function validateToken(token: string): Promise<ApiResponse | null> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);
        const startTime = Date.now();

        try {
            logger.info({
                endpoint,
                tokenLength: token.length,
                tokenPrefix: token.substring(0, 8) + '...',
                timeout
            }, '=== Starting token validation request ===');

            const requestBody = JSON.stringify({ token });
            logger.debug({
                requestBody,
                bodyLength: Buffer.byteLength(requestBody)
            }, 'Request body prepared');

            logger.debug('Initiating fetch to endpoint...');
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                },
                body: requestBody,
                signal: controller.signal,
                cache: 'no-store'
            });

            const duration = Date.now() - startTime;
            logger.info({
                duration: `${duration}ms`,
                status: res.status,
                statusText: res.statusText,
                ok: res.ok,
                redirected: res.redirected,
                type: res.type,
                url: res.url
            }, 'Fetch completed - connection established');

            const headers: Record<string, string> = {};
            res.headers.forEach((value, key) => {
                headers[key] = value;
            });
            logger.debug({ headers }, 'Response headers received');

            const contentType = res.headers.get('content-type');
            logger.debug({ contentType }, 'Content-Type header');

            if (!res.ok) {
                logger.warn({
                    status: res.status,
                    statusText: res.statusText
                }, 'Response status indicates error - attempting to read body');

                const responseText = await res.text().catch(err => {
                    logger.error({ err: err.message }, 'Failed to read error response body');
                    return 'Could not read response body';
                });

                logger.error({
                    status: res.status,
                    statusText: res.statusText,
                    responseBody: responseText,
                    responseLength: responseText.length
                }, 'Token API responded with error status');

                return null;
            }

            logger.debug('Response OK - reading response body...');
            const responseText = await res.text();
            const readDuration = Date.now() - startTime;

            logger.info({
                responseLength: responseText.length,
                totalDuration: `${readDuration}ms`
            }, 'Response body received');

            logger.debug({
                responseBody: responseText.substring(0, 500) + (responseText.length > 500 ? '...' : ''),
                fullLength: responseText.length
            }, 'Raw API response body (truncated to 500 chars)');

            let data: ApiResponse;
            try {
                logger.debug('Attempting to parse response as JSON...');
                data = JSON.parse(responseText);
                logger.info({
                    parsedData: data,
                    hasUsername: !!data.username,
                    hasGroups: !!data.groups,
                    groupsIsArray: Array.isArray(data.groups),
                    groupsLength: data.groups?.length
                }, 'Successfully parsed API response');
            } catch (parseErr: any) {
                logger.error({
                    err: parseErr.message,
                    errStack: parseErr.stack,
                    responseText: responseText.substring(0, 200),
                    contentType
                }, 'Failed to parse API response as JSON');
                return null;
            }

            if (!data.groups?.length) {
                logger.warn({
                    data,
                    hasGroups: !!data.groups,
                    groupsType: typeof data.groups,
                    groupsValue: data.groups
                }, 'API response missing or empty groups array');
                return null;
            }

            logger.info({
                username: data.username,
                groups: data.groups,
                groupCount: data.groups.length,
                totalDuration: `${Date.now() - startTime}ms`
            }, '✓ Token validation successful');

            return data;
        } catch (err: any) {
            const duration = Date.now() - startTime;

            if (err.name === 'AbortError') {
                logger.error({
                    timeout,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Token validation timed out - no response received within timeout period');
            }
            else if (err.code === 'ECONNREFUSED') {
                logger.error({
                    err: err.message,
                    code: err.code,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Connection refused - server not reachable or not listening on specified port');
            }
            else if (err.code === 'ENOTFOUND') {
                logger.error({
                    err: err.message,
                    code: err.code,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Host not found - DNS resolution failed or hostname does not exist');
            }
            else if (err.code === 'ETIMEDOUT') {
                logger.error({
                    err: err.message,
                    code: err.code,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Connection timeout - server did not respond in time');
            }
            else if (err.code === 'ECONNRESET') {
                logger.error({
                    err: err.message,
                    code: err.code,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Connection reset - server closed connection unexpectedly');
            }
            else if (err.name === 'FetchError') {
                logger.error({
                    err: err.message,
                    errName: err.name,
                    errType: err.type,
                    errCode: err.code,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Fetch error occurred');
            }
            else {
                logger.error({
                    err: err.message,
                    errName: err.name,
                    errCode: err.code,
                    errType: err.type,
                    errStack: err.stack,
                    endpoint,
                    duration: `${duration}ms`
                }, 'Token validation failed with exception');
            }
            return null;
        } finally {
            clearTimeout(timer);
        }
    }

    /**
     * Checks if a value is a JWT token (3 base64url-encoded parts separated by dots)
     */
    function isJWT(value: string): boolean {
        const jwtRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
        return jwtRegex.test(value);
    }

    /**
     * Checks if a value is a Basic Auth token (base64-encoded username:password)
     */
    function isBasicAuth(value: string): boolean {
        try {
            const base64Regex = /^[A-Za-z0-9+/]+=*$/;
            if (!base64Regex.test(value)) return false;
            const decoded = Buffer.from(value, 'base64').toString('utf8');
            return decoded.includes(':');
        } catch {
            return false;
        }
    }

    return {
        /**
         * Authenticate is not implemented - users must sign up via external service
         */
        authenticate(user: string, password: string, cb: AuthCallback): void {
            logger.info({ user }, 'authenticate() called - rejecting with signup URL');
            const err = new Error(`Signup/Login Not Implemented please use ${signupUrl} to signup`);
            (err as any).status = 405;
            cb(err, false);
        },

        /**
         * Add user is not implemented - users must sign up via external service
         */
        add_user(user: string, password: string, cb: AuthCallback): void {
            logger.info({ user }, 'add_user() called - rejecting with signup URL');
            const err = new Error(`Signup/Login Not Implemented please use ${signupUrl} to signup`);
            (err as any).status = 405;
            cb(err, false);
        },

        /**
         * Checks if a user is allowed to publish a package
         * Enforces group-based access control from config.yaml
         */
        allow_publish(user: RemoteUser, pkg: PackageAccess, cb: AllowCallback): void {
            logger.debug({
                user: user?.name,
                userGroups: user?.groups,
                package: pkg?.name,
                packagePublish: pkg.publish
            }, 'allow_publish check');

            // No user = no access
            if (!user?.name || !user?.groups?.length) {
                logger.warn({ user: user?.name, package: pkg?.name }, 'Publish denied - no valid user');
                return cb(null, false);
            }

            // Get publish rules from package configuration
            const publishGroups = pkg.publish;

            // If no publish rules defined, allow it
            if (!publishGroups || publishGroups.length === 0) {
                logger.info({ user: user.name, package: pkg.name }, 'Publish allowed - no restrictions');
                return cb(null, true);
            }

            // Check if user is in one of the allowed groups
            const allowedGroups = Array.isArray(publishGroups) ? publishGroups : publishGroups.split(/\s+/);
            const hasAccess = user.groups.some(group => allowedGroups.includes(group));

            if (hasAccess) {
                logger.info({
                    user: user.name,
                    package: pkg.name,
                    matchedGroups: user.groups.filter(g => allowedGroups.includes(g))
                }, 'Publish allowed');
                return cb(null, true);
            }

            logger.warn({
                user: user?.name,
                userGroups: user.groups,
                requiredGroups: allowedGroups,
                package: pkg?.name
            }, 'Publish denied - user not in required groups');
            cb(null, false);
        },

        /**
         * Checks if a user is allowed to unpublish a package
         * Enforces group-based access control from config.yaml
         */
        allow_unpublish(user: RemoteUser, pkg: PackageAccess, cb: AllowCallback): void {
            logger.debug({
                user: user?.name,
                userGroups: user?.groups,
                package: pkg?.name,
                packageUnpublish: pkg.unpublish
            }, 'allow_unpublish check');

            // No user = no access
            if (!user?.name || !user?.groups?.length) {
                logger.warn({ user: user?.name, package: pkg?.name }, 'Unpublish denied - no valid user');
                return cb(null, false);
            }

            // Get unpublish rules from package configuration
            const unpublishGroups = pkg.unpublish;

            // If no unpublish rules defined, allow it
            if (!unpublishGroups || unpublishGroups.length === 0) {
                logger.info({ user: user.name, package: pkg.name }, 'Unpublish allowed - no restrictions');
                return cb(null, true);
            }

            // Check if user is in one of the allowed groups
            const allowedGroups = Array.isArray(unpublishGroups) ? unpublishGroups : unpublishGroups.split(/\s+/);
            const hasAccess = user.groups.some(group => allowedGroups.includes(group));

            if (hasAccess) {
                logger.info({
                    user: user.name,
                    package: pkg.name,
                    matchedGroups: user.groups.filter(g => allowedGroups.includes(g))
                }, 'Unpublish allowed');
                return cb(null, true);
            }

            logger.warn({
                user: user?.name,
                userGroups: user.groups,
                requiredGroups: allowedGroups,
                package: pkg?.name
            }, 'Unpublish denied - user not in required groups');
            cb(null, false);
        },

        /**
         * Middleware that intercepts requests to authenticate via custom API tokens
         * - JWT tokens are passed through to Verdaccio's default handler
         * - Basic Auth tokens are passed through to Verdaccio's default handler
         * - Custom API tokens are validated via the configured endpoint
         * - Validated tokens are cached for performance (removed on validation failure)
         */
        apiJWTmiddleware() {
            return async (req: any, _res: any, next): Promise<void> => {
                const auth = req.headers?.authorization;

                if (!auth) {
                    logger.debug({
                        path: req.path,
                        method: req.method
                    }, 'No authorization header - passing to Verdaccio');
                    return next();
                }

                const token = auth.startsWith('Bearer ')
                    ? auth.slice(7)
                    : auth;

                logger.debug({
                    tokenType: auth.startsWith('Bearer ') ? 'Bearer' : 'Direct',
                    tokenLength: token.length,
                    tokenPrefix: token.substring(0, 8) + '...'
                }, 'Authorization header present');

                // Let Verdaccio handle JWT tokens
                if (isJWT(token)) {
                    logger.debug({
                        tokenPrefix: token.substring(0, 20) + '...'
                    }, 'JWT detected - passing to Verdaccio');
                    return next();
                }

                // Let Verdaccio handle Basic Auth
                if (isBasicAuth(token)) {
                    logger.debug('Basic Auth token detected - passing to Verdaccio');
                    return next();
                }

                // Check if token is cached with user data
                const cachedUser = validatedTokens.get(token);
                if (cachedUser) {
                    logger.debug({
                        username: cachedUser.username,
                        groups: cachedUser.groups
                    }, 'Token previously validated - using cached user');

                    req.remote_user = {
                        name: cachedUser.username,
                        groups: cachedUser.groups,
                        real_groups: [cachedUser.username, ...cachedUser.groups],
                    };
                    return next();
                }

                logger.info({
                    tokenPrefix: token.substring(0, 8) + '...',
                    path: req.path,
                    method: req.method
                }, 'Custom API token detected - validating via API');

                try {
                    const data = await validateToken(token);

                    if (!data) {
                        logger.warn({
                            tokenPrefix: token.substring(0, 8) + '...'
                        }, 'Invalid API token - validation returned null');

                        // Remove token from cache if it was previously valid but now invalid
                        validatedTokens.delete(token);

                        const err = new Error('Unauthorized');
                        (err as any).status = 401;
                        return next(err);
                    }

                    const username = data.username || 'api-user';
                    const groups = data.groups!;

                    // Store user data in cache for future requests
                    validatedTokens.set(token, { username, groups });

                    req.remote_user = {
                        name: username,
                        groups,
                        real_groups: [username, ...groups],
                    } as RemoteUser;

                    logger.info({
                        username,
                        groups,
                        path: req.path,
                        source: 'api'
                    }, '✓ API authenticated via custom token');

                    next();
                } catch (err: any) {
                    logger.error({
                        err: err.message,
                        errName: err.name,
                        errStack: err.stack,
                        path: req.path
                    }, 'Token validation error in middleware');

                    // Remove token from cache on validation error
                    validatedTokens.delete(token);

                    const error = new Error('Unauthorized');
                    (error as any).status = 401;
                    return next(error);
                }
            };
        },
    };
};