import { ComboboxItem, Select } from "@mantine/core";
import { useState } from "react";
import i18n from "../../lib/i18n/i18n";
import {
  SupportedLanguage,
  getLanguageName,
  languages,
} from "../../lib/i18n/locales";

export const LanguageSelector = () => {
  const [language, setLanguage] = useState<ComboboxItem>({
    value: i18n.language,
    label: getLanguageName(i18n.language as SupportedLanguage),
  });

  const languageOptions = Object.entries(languages).map(([code, name]) => ({
    value: code,
    label: name,
  }));

  const handleLanguageChange = (option: string) => {
    i18n.changeLanguage(option as SupportedLanguage);
    setLanguage({
      value: option,
      label: getLanguageName(option as SupportedLanguage),
    });
  };

  return (
    <Select
      data={languageOptions}
      value={language ? language.value : null}
      onChange={(_value, option) => handleLanguageChange(option.value)}
      allowDeselect={false}
      pos="absolute"
      right={10}
      top={10}
    />
  );
};
