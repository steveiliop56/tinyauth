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

interface Props {
  onSubmit: (data: LoginSchema) => void;
  loading?: boolean;
}

export const LoginForm = (props: Props) => {
  const { onSubmit, loading } = props;
  const { t } = useTranslation();

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
            <FormItem className="mb-4">
              <FormLabel>{t("loginUsername")}</FormLabel>
              <FormControl>
                <Input
                  placeholder={t("loginUsername")}
                  disabled={loading}
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
            <FormItem className="mb-4">
              <div className="relative">
                <FormLabel className="mb-2">{t("loginPassword")}</FormLabel>
                <FormControl>
                  <Input
                    placeholder={t("loginPassword")}
                    type="password"
                    disabled={loading}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
                <a
                  href="/forgot-password"
                  className="text-muted-foreground text-sm absolute right-0 bottom-10"
                >
                  {t("forgotPasswordTitle")}
                </a>
              </div>
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
