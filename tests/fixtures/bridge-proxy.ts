export default {
  fetch(request: Request, env: { AUTH_SERVICE: Fetcher }): Promise<Response> {
    return env.AUTH_SERVICE.fetch(request);
  },
};
