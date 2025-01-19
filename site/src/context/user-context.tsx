import { useQuery } from "@tanstack/react-query";
import React, { createContext, useContext } from "react";
import { UserContextSchemaType } from "../schemas/user-context-schema";
import axios from "axios";

const UserContext = createContext<UserContextSchemaType | null>(null);

export const UserContextProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const {
    data: userContext,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["isLoggedIn"],
    queryFn: async () => {
      const res = await axios.get("/api/status");
      return res.data;
    },
  });

  if (error && !isLoading) {
    throw error;
  }

  return (
    <UserContext.Provider value={userContext}>{children}</UserContext.Provider>
  );
};

export const useUserContext = () => {
  const context = useContext(UserContext);

  if (context === null) {
    throw new Error("useUserContext must be used within a UserContextProvider");
  }

  return context;
};
