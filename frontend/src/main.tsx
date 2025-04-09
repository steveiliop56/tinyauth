import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route } from "react-router";
import { Routes } from "react-router";
import { UserContextProvider } from "./context/user-context.tsx";
import { LoginPage } from "./pages/login-page.tsx";
import { LogoutPage } from "./pages/logout-page.tsx";
import { ContinuePage } from "./pages/continue-page.tsx";
import { NotFoundPage } from "./pages/not-found-page.tsx";
import { UnauthorizedPage } from "./pages/unauthorized-page.tsx";
import { InternalServerError } from "./pages/internal-server-error.tsx";
import { TotpPage } from "./pages/totp-page.tsx";
import { AppContextProvider } from "./context/app-context.tsx";
import "./lib/i18n/i18n.ts";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      suspense: true,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider defaultColorScheme="auto">
      <QueryClientProvider client={queryClient}>
        <Notifications />
        <AppContextProvider>
          <UserContextProvider>
            <BrowserRouter>
              <Routes>
                <Route path="/" element={<App />} />
                <Route path="/login" element={<LoginPage />} />
                <Route path="/totp" element={<TotpPage />} />
                <Route path="/logout" element={<LogoutPage />} />
                <Route path="/continue" element={<ContinuePage />} />
                <Route path="/unauthorized" element={<UnauthorizedPage />} />
                <Route path="/error" element={<InternalServerError />} />
                <Route path="*" element={<NotFoundPage />} />
              </Routes>
            </BrowserRouter>
          </UserContextProvider>
        </AppContextProvider>
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
