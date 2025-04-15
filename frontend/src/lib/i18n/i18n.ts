import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import ChainedBackend from "i18next-chained-backend";
import resourcesToBackend from "i18next-resources-to-backend";
import HttpBackend from "i18next-http-backend";

const backends = [
  HttpBackend,
  resourcesToBackend(
    (language: string) => import(`./locales/${language}.json`),
  ),
]

const backendOptions =  [
  {
    loadPath: "https://cdn.tinyauth.app/i18n/v1/{{lng}}.json",
  },
  {}
]

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
      backends: import.meta.env.MODE !== "development" ? backends : backends.reverse(),
      backendOptions: import.meta.env.MODE !== "development" ? backendOptions : backendOptions.reverse()
    },
  });

export default i18n;
