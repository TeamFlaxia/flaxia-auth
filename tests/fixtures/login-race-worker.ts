// Test-only worker: insert the password-change interleaving at the exact read.
import app from '../../src/index';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const replacement = request.headers.get('X-Test-Replacement');
    if (!replacement) return app.fetch(request, env, ctx);
    const [salt, verifier] = replacement.split(':');
    let injected = false;
    const db = env.DB;
    const wrapped = new Proxy(db, {
      get(target, key) {
        if (key !== 'prepare') {
          const value = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        }
        return (sql: string) => {
          const statement = target.prepare(sql);
          if (sql !== 'SELECT * FROM users WHERE id = ?') return statement;
          return new Proxy(statement, {
            get(stmt, prop) {
              if (prop !== 'bind') {
                const value = Reflect.get(stmt, prop, stmt);
                return typeof value === 'function' ? value.bind(stmt) : value;
              }
              return (...args: unknown[]) => {
                const bound = stmt.bind(...args);
                return new Proxy(bound, {
                  get(b, p) {
                    if (p !== 'first') {
                      const value = Reflect.get(b, p, b);
                      return typeof value === 'function' ? value.bind(b) : value;
                    }
                    return async () => {
                      const oldUser = await b.first();
                      if (!injected && oldUser) {
                        injected = true;
                        // Equivalent observable state to a successful credential commit:
                        // replace the verifier and revoke the user's existing sessions.
                        await db.batch([
                          db.prepare('UPDATE users SET srp_salt = ?, srp_verifier = ? WHERE id = ?').bind(salt, verifier, args[0]),
                          db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(args[0]),
                        ]);
                      }
                      return oldUser;
                    };
                  },
                });
              };
            },
          });
        };
      },
    });
    const response = await app.fetch(request, { ...env, DB: wrapped }, ctx);
    response.headers.set('X-Test-Interleaved', injected ? 'yes' : 'no');
    return response;
  },
};
