import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import resourcesToBackend from "i18next-resources-to-backend";
import { languages } from "./locales";

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .use(
    resourcesToBackend(
      (language: string) => import(`./locales/${language}.json`),
    ),
  )
  .init({
    fallbackLng: "en",
    debug: import.meta.env.MODE === "development",
    nonExplicitSupportedLngs: true,
    supportedLngs: Object.keys(languages),
    load: "currentOnly",
    detection: {
      lookupLocalStorage: "tinyauth-lang",
    },
  });

export default i18n;
