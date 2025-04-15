import { useSuspenseQuery } from "@tanstack/react-query";
import React, { createContext, useContext } from "react";
import axios from "axios";
import { UserContextSchemaType } from "../schemas/user-context-schema";

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
  } = useSuspenseQuery({
    queryKey: ["userContext"],
    queryFn: async () => {
      const res = await axios.get("/api/user");
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
