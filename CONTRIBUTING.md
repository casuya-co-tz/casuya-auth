# CONTRIBUTING — casuya-auth

## Phase 3 Implementation Law

Before approving any code, every developer must answer:

| # | Question | Must Be |
|---|----------|---------|
| 1 | Is this a shared service? | Yes |
| 2 | Is this feature generic and reusable? | Yes |
| 3 | Can another repository use it? | Yes |
| 4 | Is it provider-based? | Yes |
| 5 | Can providers be replaced without rewriting? | Yes |
| 6 | Is it API-first? | Yes |
| 7 | Does it avoid business-specific logic? | Yes |
| 8 | Does it avoid Phase 1/2 responsibilities? | Yes |
| 9 | Can it scale to millions of users? | Yes |
| 10 | Will future developers understand its purpose? | Yes |
| 11 | Is it modular? | Yes |
| 12 | Is it backward compatible? | Yes |
| 13 | Is it secure? | Yes |
| 14 | Is it fully testable? | Yes |

If any answer is **"No"**, the implementation must not be approved.

---

## Development Workflow

1. **Create an interface** in `src/<module>/<module>.service.interface.ts`
2. **Implement** in `src/<module>/<module>.service.ts`
3. **Export** via `src/<module>/index.ts`
4. **Test** in `tests/<module>.test.ts`
5. **Verify** — run `npm run typecheck && npm test` before committing

## Code Conventions

- No comments in source code
- Async/await over raw promises
- Interfaces before implementations
- Provider pattern for all extensible boundaries
- Every public API must have a test

## NEVER Build

- Authentication systems (this IS the auth system)
- Payment, notification, analytics logic
- School-specific business logic
- Lesson execution or packaging
- Synchronization systems
