import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { Layout } from "./components/layout/layout.tsx";
import { createBrowserRouter, RouterProvider } from "react-router";
import { LoginPage } from "./pages/login-page.tsx";
import { App } from "./App.tsx";
import { ErrorPage } from "./pages/error-page.tsx";
import { NotFoundPage } from "./pages/not-found-page.tsx";
import { ContinuePage } from "./pages/continue-page.tsx";
import { TotpPage } from "./pages/totp-page.tsx";
import { ForgotPasswordPage } from "./pages/forgot-password-page.tsx";
import { LogoutPage } from "./pages/logout-page.tsx";
import { UnauthorizedPage } from "./pages/unauthorized-page.tsx";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppContextProvider } from "./context/app-context.tsx";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    errorElement: <ErrorPage />,
  },
  {
    path: "/login",
    element: <LoginPage />,
    errorElement: <ErrorPage />,
  },
  {
    path: "/logout",
    element: <LogoutPage />,
    errorElement: <ErrorPage />,
  },
  {
    path: "/continue",
    element: <ContinuePage />,
    errorElement: <ErrorPage />,
  },
  {
    path: "/totp",
    element: <TotpPage />,
    errorElement: <ErrorPage />,
  },
  {
    path: "/forgot-password",
    element: <ForgotPasswordPage />,
    errorElement: <ErrorPage />,
  },
  {
    path: "/unauthorized",
    element: <UnauthorizedPage />,
    errorElement: <ErrorPage />,
  },
  {
    path: "*",
    element: <NotFoundPage />,
    errorElement: <ErrorPage />,
  },
]);

const queryClient = new QueryClient();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AppContextProvider>
        <Layout>
          <RouterProvider router={router} />
        </Layout>
      </AppContextProvider>
    </QueryClientProvider>
  </StrictMode>,
);
