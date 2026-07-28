# opendevops documentation website

The product landing page and Fumadocs documentation portal live in this directory so the existing
Python package and dashboard build remain independent.

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Documentation content is under
`content/docs`; the landing page is `src/app/page.tsx`.

Before submitting changes:

```bash
npm run typecheck
npm run lint
npm run build
```
