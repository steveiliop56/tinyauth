import { useTranslation } from "react-i18next";
import { Input } from "../ui/input";
import { z } from "zod";
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

export const LoginForm = () => {
  const { t } = useTranslation();

  const schema = z.object({
    username: z.string(),
    password: z.string(),
  });

  type LoginFormType = z.infer<typeof schema>;

  const form = useForm<LoginFormType>({
    resolver: zodResolver(schema),
  });

  const onSubmit = (data: LoginFormType) => {
    // Handle login logic here
    console.log("Login data:", data);
  };

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
                <Input placeholder={t("loginUsername")} {...field} />
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
              <FormLabel className="flex flex-row justify-between">
                <span>{t("loginPassword")}</span>
                <a
                  href="/forgot-password"
                  className="text-muted-foreground font-normal"
                >
                  {t("forgotPasswordTitle")}
                </a>
              </FormLabel>
              <FormControl>
                <Input
                  placeholder={t("loginPassword")}
                  type="password"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button className="w-full" type="submit">
          {t("loginSubmit")}
        </Button>
      </form>
    </Form>
  );
};
