import {
  appContextSchema,
  AppContextSchema,
} from "@/schemas/app-context-schema";
import { createContext, useContext } from "react";
import { useSuspenseQuery } from "@tanstack/react-query";
import axios from "axios";

const AppContext = createContext<AppContextSchema | null>(null);

export const AppContextProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const { isFetching, data, error } = useSuspenseQuery({
    queryKey: ["app"],
    queryFn: () => axios.get("/api/context/app").then((res) => res.data),
  });

  if (error && !isFetching) {
    throw error;
  }

  const validated = appContextSchema.safeParse(data);

  if (validated.success === false) {
    throw validated.error;
  }

  return (
    <AppContext.Provider value={validated.data}>{children}</AppContext.Provider>
  );
};

export const useAppContext = () => {
  const context = useContext(AppContext);

  if (!context) {
    throw new Error("useAppContext must be used within an AppContextProvider");
  }

  return context;
};
