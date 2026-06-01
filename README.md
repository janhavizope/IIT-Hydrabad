This is the frontend for **APK Malware Analyzer**, built with the Next.js App Router, TypeScript, and Tailwind CSS.

## Suggested Folder Structure

```text
frontend/
├── app/
├── components/
│   ├── ui/
│   └── layout/
├── services/
│   └── api/
├── hooks/
├── types/
└── utils/
```

## Folder Purpose

- `app/`: App Router entry point for pages, layouts, routes, and route-level UI.
- `components/`: Reusable UI building blocks shared across the dashboard.
- `components/ui/`: Small presentational elements such as buttons, badges, cards, and inputs.
- `components/layout/`: Higher-level layout pieces such as sidebars, headers, nav bars, and shells.
- `services/`: Business logic and external integrations.
- `services/api/`: API wrappers for malware scanning, upload handling, analytics, and backend calls.
- `hooks/`: Custom React hooks for shared client-side logic.
- `types/`: Central TypeScript interfaces and type definitions.
- `utils/`: Pure helper functions, constants, formatting helpers, and small shared utilities.

This structure keeps the MVP clean now and makes it easy to scale into more features later.

## Notes

- The project already uses the Next.js App Router, so route files live in `app/`.
- TypeScript and Tailwind CSS are already configured in the project dependencies.

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
