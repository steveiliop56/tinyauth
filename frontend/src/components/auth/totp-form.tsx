import { Form, FormControl, FormField, FormItem } from "../ui/form";
import { Input } from "../ui/input";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { totpSchema, TotpSchema } from "@/schemas/totp-schema";
import { useTranslation } from "react-i18next";
import z from "zod";

interface Props {
  formId: string;
  onSubmit: (code: TotpSchema) => void;
}

export const TotpForm = (props: Props) => {
  const { formId, onSubmit } = props;
  const { t } = useTranslation();

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const form = useForm<TotpSchema>({
    resolver: zodResolver(totpSchema),
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, "").slice(0, 6);
    form.setValue("code", value, { shouldDirty: true, shouldValidate: true });
    if (value.length === 6) {
      form.handleSubmit(onSubmit)();
    }
  };

  return (
    <Form {...form}>
      <form id={formId} onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          control={form.control}
          name="code"
          render={({ field }) => (
            <FormItem>
              <FormControl>
                <Input
                  {...field}
                  id="totp-code"
                  name="code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  maxLength={6}
                  placeholder="XXXXXX"
                  onChange={handleChange}
                  className="text-center"
                />
              </FormControl>
            </FormItem>
          )}
        />
      </form>
    </Form>
  );
};
