import { MoonIcon, SunIcon } from "lucide-react";
import { useTheme } from "../providers/theme-provider";
import { Button } from "../ui/button";

export const ThemeSwitch = () => {
  const { darkMode, setDarkMode } = useTheme();

  const toggleTheme = () => {
    setDarkMode(!darkMode);
  };

  return (
    <Button
      className="bg-card hover:bg-card/90 text-card-foreground"
      aria-label={`Switch to ${darkMode ? "light" : "dark"} mode`}
      onClick={() => {
        toggleTheme();
      }}
    >
      {darkMode ? <SunIcon /> : <MoonIcon />}
    </Button>
  );
};
