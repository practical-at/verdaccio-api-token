import { Logger } from '@verdaccio/types';

interface ApiTokenAuthConfig {
    endpoint: string;
    timeout?: number;
}

interface VerdaccioStuff {
    logger: Logger;
}

interface ApiResponse {
    groups?: string[];
}

type AuthCallback = (err: Error | null, groups?: string[] | false) => void;

interface AuthPlugin {
    authenticate(user: string, password: string, cb: AuthCallback): void;
}

export = function apiTokenAuth(
    config: ApiTokenAuthConfig,
    stuff: VerdaccioStuff
): AuthPlugin {
    const logger = stuff.logger;
    const endpoint = config.endpoint;
    const timeout = config.timeout || 5000;

    if (!endpoint) {
        logger.error('verdaccio-api-token: "endpoint" required in config');
        return {
            authenticate() {
                // Empty implementation when config is invalid
            }
        };
    }

    return {
        authenticate(
            user: string,
            password: string,
            cb: AuthCallback
        ): void {
            if (!password) {
                logger.debug('No token provided');
                return cb(null, false);
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: password }),
                signal: controller.signal
            })
                .then(res => {
                    clearTimeout(timeoutId);
                    if (!res.ok) {
                        logger.warn(`API error: ${res.status}`);
                        return cb(null, false);
                    }
                    return res.json();
                })
                .then((data: ApiResponse) => {
                    const groups = data?.groups || [];
                    if (!groups.length) {
                        logger.warn('Empty groups from API');
                        return cb(null, false);
                    }
                    logger.debug({ groups }, 'API auth success');
                    cb(null, groups);
                })
                .catch((err: Error) => {
                    clearTimeout(timeoutId);
                    logger.warn({ err: err.message }, 'API auth failed');
                    cb(null, false);
                });
        }
    };
};