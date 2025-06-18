TODO:

- ✅ Add `withSimplerAuth(handler,config?:{scope?:string})` fetch wrapper to have a one-liner that logs in if unauthenticated and passes user simple user-do access to ctx.
- Create minimal demo `withSimplerAuth`
- Create `./entrypoint.js` that imports `../../main`
- Create minimal demo with entrypoint
- Create `withPathKv(handler,config:{binding:string})` that can wrap this to add the path-kv pattern
- If this works, see if I can do `withPathKv(withSimplerAuth(withStripeflare(handler)))`. That'd be sick!
