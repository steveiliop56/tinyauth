import { TextInput, PasswordInput, Button } from "@mantine/core";
import { useForm, zodResolver } from "@mantine/form";
import { LoginFormValues, loginSchema } from "../../schemas/login-schema";
import { useTranslation } from "react-i18next";

interface LoginFormProps {
  isLoading: boolean;
  onSubmit: (values: LoginFormValues) => void;
}

export const LoginForm = (props: LoginFormProps) => {
  const { isLoading, onSubmit } = props;
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
        required
        disabled={isLoading}
        key={form.key("username")}
        {...form.getInputProps("username")}
      />
      <PasswordInput
        label={t("loginPassword")}
        placeholder="password"
        required
        mt="md"
        disabled={isLoading}
        key={form.key("password")}
        {...form.getInputProps("password")}
      />
      <Button fullWidth mt="xl" type="submit" loading={isLoading}>
        {t("loginSubmit")}
      </Button>
    </form>
  );
};
