import { useTranslation } from "react-i18next";
import { Input } from "../ui/input";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../ui/form";
import { Button } from "../ui/button";
import { loginSchema, LoginSchema } from "@/schemas/login-schema";
import { useAppContext } from "@/context/app-context";
import z from "zod";

interface Props {
  onSubmit: (data: LoginSchema) => void;
  loading?: boolean;
}

export const LoginForm = (props: Props) => {
  const { onSubmit, loading } = props;
  const { t } = useTranslation();
  const {
    usernameTitle,
    passwordTitle,
    usernamePlaceholder,
    passwordPlaceholder
  } = useAppContext();

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const form = useForm<LoginSchema>({
    resolver: zodResolver(loginSchema),
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem className="mb-4 gap-0">
              <FormLabel className="mb-2">{usernameTitle || t("loginUsername")}</FormLabel>
              <FormControl className="mb-1">
                <Input
                  placeholder={usernamePlaceholder || t("loginUsername")}
                  disabled={loading}
                  autoComplete="username"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem className="mb-4 gap-0">
              <div className="relative mb-1">
                <FormLabel className="mb-2">{passwordTitle || t("loginPassword")}</FormLabel>
                <FormControl>
                  <Input
                    placeholder={passwordPlaceholder || t("loginPassword")}
                    type="password"
                    disabled={loading}
                    autoComplete="current-password"
                    {...field}
                  />
                </FormControl>
                <a
                  href="/forgot-password"
                  className="text-muted-foreground text-sm absolute right-0 bottom-[2.565rem]" // 2.565 is *just* perfect
                >
                  {t("forgotPasswordTitle")}
                </a>
              </div>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button className="w-full" type="submit" loading={loading}>
          {t("loginSubmit")}
        </Button>
      </form>
    </Form>
  );
};
