import { Center, Flex } from "@mantine/core";
import { ReactNode } from "react";

export const Layout = ({ children }: { children: ReactNode }) => {
  return (
    <Center style={{ minHeight: "100vh" }}>
      <Flex direction="column" flex="1" maw={350}>
        {children}
      </Flex>
    </Center>
  );
};
