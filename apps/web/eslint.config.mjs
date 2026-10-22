import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const config = [
  ...nextVitals,
  ...nextTs,
  {
    // Heading order: cards come from AppCard (h2 title); the library Card renders an h3 under the h1.
    files: ["src/**/*.{ts,tsx,jsx}"],
    ignores: ["src/**/*.test.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@adminlte/react",
              importNames: ["Card"],
              message: "Use AppCard from '@/components/app-card' (h2 card title keeps heading order).",
            },
          ],
        },
      ],
    },
  },
  { ignores: [".next/**", ".test-build/**", "node_modules/**", "next-env.d.ts"] },
];

export default config;
