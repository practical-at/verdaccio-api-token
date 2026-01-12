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
            authenticate() {},
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

            console.info("Response", res)

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

    return {
        // npm login
        authenticate(user: string, token: string, cb: AuthCallback): void {
            if (!token) return cb(null, false);

            validateToken(token)
                .then((data) => {
                    if (!data) {
                        logger.warn('Invalid token (login)');
                        return cb(null, false);
                    }

                    const username = data.username || user || 'api-user';
                    const groups = [username, ...data.groups!];

                    logger.debug({ username, groups }, 'Login authenticated');
                    cb(null, groups);
                })
                .catch(() => cb(null, false));
        },

        // Registry / API access
        apiJWTmiddleware() {
            return async (req: any, _res: any, next): Promise<void> => {
                const auth = req.headers?.authorization;
                if (!auth) return next();


                const token = auth.startsWith('Bearer ')
                    ? auth.slice(7)
                    : auth;

                console.info("Auth:", auth)
                console.info("Token:", token)


                const data = await validateToken(token);


                if (!data) {
                    logger.warn('Invalid token (api)');
                    const err = new Error('Unauthorized');
                    (err as any).status = 401;
                    return next(err);
                }

                const username = data.username || 'api-user';
                const groups = data.groups!;

                req.remote_user = {
                    name: username,
                    groups,
                    real_groups: [username, ...groups],
                } as RemoteUser;

                logger.debug({ username, groups }, 'API authenticated');
                next();
            };
        },
    };
};
