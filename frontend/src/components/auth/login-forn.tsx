import { TextInput, PasswordInput, Button, Anchor, Group, Text } from "@mantine/core";
import { useForm, zodResolver } from "@mantine/form";
import { LoginFormValues, loginSchema } from "../../schemas/login-schema";
import { useTranslation } from "react-i18next";

interface LoginFormProps {
  isPending: boolean;
  onSubmit: (values: LoginFormValues) => void;
}

export const LoginForm = (props: LoginFormProps) => {
  const { isPending, onSubmit } = props;
  const { t } = useTranslation();

  const form = useForm({
    mode: "uncontrolled",
    initialValues: {
      username: "",
      password: "",
    },
    validate: zodResolver(loginSchema),
  });

  return (
    <form onSubmit={form.onSubmit(onSubmit)}>
      <TextInput
        label={t("loginUsername")}
        placeholder="username"
        disabled={isPending}
        required
        withAsterisk={false}
        key={form.key("username")}
        {...form.getInputProps("username")}
      />
      <Group justify="space-between" mb={5} mt="md">
        <Text component="label" htmlFor=".password-input" size="sm" fw={500}>
        {t("loginPassword")}
        </Text>

        <Anchor href="#" onClick={() => window.location.replace("/forgot-password")} pt={2} fw={500} fz="xs">
          {t('forgotPasswordTitle')}
        </Anchor>
      </Group>
      <PasswordInput
        className="password-input"
        placeholder="password"
        required
        disabled={isPending}
        key={form.key("password")}
        {...form.getInputProps("password")}
      />
      <Button fullWidth mt="xl" type="submit" loading={isPending}>
        {t("loginSubmit")}
      </Button>
    </form>
  );
};
