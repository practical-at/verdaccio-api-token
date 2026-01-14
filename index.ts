import { Logger } from '@verdaccio/types';

interface ApiTokenAuthConfig {
    endpoint: string;
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

interface RemoteUser {
    name: string;
    groups: string[];
    real_groups: string[];
}

interface AuthPlugin {
    authenticate(user: string, password: string, cb: AuthCallback): void;
    apiJWTmiddleware(): (
        req: any,
        res: any,
        next: (err?: any) => void
    ) => Promise<void>;
}
export = function apiTokenAuth(
    config: ApiTokenAuthConfig,
    stuff: VerdaccioStuff
): AuthPlugin {
    const logger = stuff.logger;
    const endpoint = config.endpoint;
    const timeout = config.timeout ?? 5000;

    if (!endpoint) {
        logger.error('verdaccio-api-token: "endpoint" missing');
        return {
            authenticate(user, password, cb) {
                cb(null, false);
            },
            apiJWTmiddleware() {
                return async (_req, _res, next) => next();
            },
        };
    }

    async function validateToken(token: string): Promise<ApiResponse | null> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token }),
                signal: controller.signal,
            });

            if (!res.ok) {
                logger.warn(`Token API responded ${res.status}`);
                return null;
            }

            const data: ApiResponse = await res.json();
            return data.groups?.length ? data : null;
        } catch (err: any) {
            logger.warn({ err: err.message }, 'Token validation failed');
            return null;
        } finally {
            clearTimeout(timer);
        }
    }

    function isJWT(value: string): boolean {
        const jwtRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
        return jwtRegex.test(value);
    }

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
        authenticate(user: string, password: string, cb: AuthCallback): void {
            logger.debug({ user }, 'Passing login to Verdaccio');
            cb(null, false);
        },

        apiJWTmiddleware() {
            return async (req: any, _res: any, next): Promise<void> => {
                const auth = req.headers?.authorization;

                // No auth header - let Verdaccio handle it (might be anonymous access)
                if (!auth) {
                    logger.debug('No authorization header, passing to Verdaccio');
                    return next();
                }

                const token = auth.startsWith('Bearer ')
                    ? auth.slice(7)
                    : auth;

                // JWT (Web UI) - let Verdaccio's JWT middleware handle it
                if (isJWT(token)) {
                    logger.debug('JWT detected, passing to Verdaccio');
                    return next();
                }

                // Basic Auth (npm login with htpasswd) - let Verdaccio handle it
                if (isBasicAuth(token)) {
                    logger.debug('Basic Auth token detected, passing to Verdaccio');
                    return next();
                }

                // Custom API token - validate it
                logger.debug('Custom token detected, validating via API');

                try {
                    const data = await validateToken(token);

                    if (!data) {
                        logger.warn('Invalid API token');
                        const err = new Error('Unauthorized');
                        (err as any).status = 401;
                        return next(err);
                    }

                    const username = data.username || 'api-user';
                    const groups = data.groups!;

                    // Set remote_user for Verdaccio's authorization
                    req.remote_user = {
                        name: username,
                        groups,
                        real_groups: [username, ...groups],
                    } as RemoteUser;

                    logger.info({ username, groups }, 'API authenticated via custom token');
                    next();
                } catch (err: any) {
                    logger.error({ err: err.message }, 'Token validation error');
                    const error = new Error('Unauthorized');
                    (error as any).status = 401;
                    return next(error);
                }
            };
        },
    };
};

