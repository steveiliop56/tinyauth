import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import ChainedBackend from "i18next-chained-backend";
import resourcesToBackend from "i18next-resources-to-backend";
import HttpBackend from "i18next-http-backend";

i18n
  .use(ChainedBackend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    debug: import.meta.env.MODE === "development",

    interpolation: {
      escapeValue: false,
    },

    load: "currentOnly",

    backend: {
      backends: [
        HttpBackend,
        resourcesToBackend(
          (language: string) => import(`./locales/${language}.json`),
        ),
      ],
      backendOptions: [
        {
          loadPath: "https://cdn.tinyauth.app/i18n/{{lng}}.json",
        },
      ],
    },
  });

export default i18n;
