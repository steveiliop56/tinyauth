import React from "react";
import { createContext, useEffect, useState } from "react";

interface ThemeSchema {
  darkMode: boolean;
  setDarkMode: (darkMode: boolean) => void;
}

const ThemeContext = createContext<ThemeSchema | null>(null);

export const ThemeProvider = ({ children }: { children: React.ReactNode }) => {
  const [darkMode, setDarkMode] = useState<boolean>(false);

  useEffect(() => {
    const storedTheme = localStorage.getItem("tinyauth-theme");
    if (storedTheme) {
      setDarkMode(storedTheme === "dark");
      return;
    }
    const prefersDark = window.matchMedia(
      "(prefers-color-scheme: dark)",
    ).matches;
    setDarkMode(prefersDark);
  }, []);

  useEffect(() => {
    const rootElement = document.documentElement;
    rootElement.classList.remove("dark", "light");
    rootElement.classList.add(darkMode ? "dark" : "light");
  }, [darkMode]);

  const values = {
    darkMode,
    setDarkMode: (darkMode: boolean) => {
      localStorage.setItem("tinyauth-theme", darkMode ? "dark" : "light");
      setDarkMode(darkMode);
    },
  };

  return (
    <ThemeContext.Provider value={values}>{children}</ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = React.useContext(ThemeContext);

  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }

  return context;
};
