import { AppContextSchema } from "@/schemas/app-context-schema";
import { createContext, useContext } from "react";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";

const AppContext = createContext<AppContextSchema | null>(null);

export const AppContextProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const { isPending, isError, data, error } = useQuery({
    queryKey: ["status"],
    queryFn: () => axios.get("/api/app").then((res) => res.data),
  });

  if (isPending) {
    return;
  }

  if (isError) {
    throw error;
  }

  return <AppContext.Provider value={data}>{children}</AppContext.Provider>;
};

export const useAppContext = () => {
  const context = useContext(AppContext);

  if (!context) {
    throw new Error("useAppContext must be used within an AppContextProvider");
  }

  return context;
};
