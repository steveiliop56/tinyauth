import { Paper, Text, TypographyStylesProvider } from "@mantine/core";
import { Layout } from "../components/layouts/layout";
import { useTranslation } from "react-i18next";
import { useAppContext } from "../context/app-context";
import Markdown from 'react-markdown'

export const ForgotPasswordPage = () => {
  const { t } = useTranslation();
  const { forgotPasswordMessage } = useAppContext();

  return (
    <Layout>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <Text size="xl" fw={700}>
          {t("forgotPasswordTitle")}
        </Text>
        <TypographyStylesProvider>
            <Markdown>
                {forgotPasswordMessage}
            </Markdown>
        </TypographyStylesProvider>
      </Paper>
    </Layout>
  );
};
