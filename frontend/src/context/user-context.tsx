import {
  userContextSchema,
  UserContextSchema,
} from "@/schemas/user-context-schema";
import { createContext, useContext } from "react";
import { useSuspenseQuery } from "@tanstack/react-query";
import axios from "axios";

const UserContext = createContext<UserContextSchema | null>(null);

export const UserContextProvider = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  const { isFetching, data, error } = useSuspenseQuery({
    queryKey: ["user"],
    queryFn: () => axios.get("/api/user").then((res) => res.data),
  });

  if (error && !isFetching) {
    throw error;
  }

  const validated = userContextSchema.safeParse(data);

  if (validated.success === false) {
    throw validated.error;
  }

  return (
    <UserContext.Provider value={validated.data}>
      {children}
    </UserContext.Provider>
  );
};

export const useUserContext = () => {
  const context = useContext(UserContext);

  if (!context) {
    throw new Error(
      "useUserContext must be used within an UserContextProvider",
    );
  }

  return context;
};
