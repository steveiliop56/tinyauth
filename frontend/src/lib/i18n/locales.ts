export const languages = {
  "af-ZA": "Afrikaans",
  "ar-SA": "العربية",
  "ca-ES": "Català",
  "cs-CZ": "Čeština",
  "da-DK": "Dansk",
  "de-DE": "Deutsch",
  "el-GR": "Ελληνικά",
  "en-US": "English",
  "es-ES": "Español",
  "fi-FI": "Suomi",
  "fr-FR": "Français",
  "he-IL": "עברית",
  "hu-HU": "Magyar",
  "it-IT": "Italiano",
  "ja-JP": "日本語",
  "ko-KR": "한국어",
  "nl-NL": "Nederlands",
  "no-NO": "Norsk",
  "pl-PL": "Polski",
  "pt-BR": "Português",
  "pt-PT": "Português",
  "ro-RO": "Română",
  "ru-RU": "Русский",
  "sr-SP": "Српски",
  "sv-SE": "Svenska",
  "tr-TR": "Türkçe",
  "uk-UA": "Українська",
  "vi-VN": "Tiếng Việt",
  "zh-CN": "简体中文",
  "zh-TW": "繁體中文（台灣）",
};

export type SupportedLanguage = keyof typeof languages;

export const getLanguageName = (language: SupportedLanguage): string =>
  languages[language];
