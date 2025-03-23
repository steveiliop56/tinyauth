import { Navigate } from "react-router";
import { useUserContext } from "./context/user-context";
import { LogoutPage } from "./pages/logout-page";

export const App = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri");

  const { isLoggedIn } = useUserContext();

  if (!isLoggedIn) {
    return <Navigate to={`/login?redirect_uri=${redirectUri}`} />;
  }

  return <LogoutPage />;
};
