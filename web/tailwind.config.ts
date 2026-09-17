import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0b0f1a",
        panel: "#131a2a",
        edge: "#243049",
      },
    },
  },
  plugins: [],
};
export default config;
