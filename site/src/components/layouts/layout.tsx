import { Center, Flex } from "@mantine/core";
import { ReactNode } from "react";
import { LanguageSelector } from "../language-selector/language-selector";

export const Layout = ({ children }: { children: ReactNode }) => {
  return (
    <>
      <LanguageSelector />
      <Center style={{ minHeight: "100vh" }}>
        <Flex direction="column" flex="1" maw={340}>
          {children}
        </Flex>
      </Center>
    </>
  );
};
