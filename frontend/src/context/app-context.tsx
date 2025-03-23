import { useQuery } from "@tanstack/react-query";
import React, { createContext, useContext } from "react";
import axios from "axios";
import { AppContextSchemaType } from "../schemas/app-context-schema";

const AppContext = createContext<AppContextSchemaType | null>(null);

export const AppContextProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const {
    data: userContext,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["appContext"],
    queryFn: async () => {
      const res = await axios.get("/api/app");
      return res.data;
    },
  });

  if (error && !isLoading) {
    throw error;
  }

  return (
    <AppContext.Provider value={userContext}>{children}</AppContext.Provider>
  );
};

export const useAppContext = () => {
  const context = useContext(AppContext);

  if (context === null) {
    throw new Error("useAppContext must be used within an AppContextProvider");
  }

  return context;
};
