# PR Agent Frontend (Vite + React + Tailwind)

This folder contains a minimal Vite + React app wired with Tailwind CSS. It polls the backend every 3 seconds (GET /jobs) and shows agent outputs for each job. It can also start a job by POSTing to `/start-job`.

Quick start

1. From this folder install dependencies:

```bash
cd frontend
npm install
```

2. Run the dev server:

```bash
npm run dev
```

By default the frontend expects the backend at `http://localhost:8000`.

To point the frontend to a different backend URL during development, set a Vite env var prefixed with `VITE_` (these are exposed to the browser). For example:

```bash
# from the `frontend` folder
VITE_BACKEND_URL=http://localhost:8000 npm run dev
```

Inside the app the client reads `import.meta.env.VITE_BACKEND_URL` and falls back to `http://localhost:8000` if unset.

Notes
- The backend must allow CORS (the provided FastAPI in this repo already does).
- Tailwind is configured in `tailwind.config.js` and PostCSS in `postcss.config.cjs`.
