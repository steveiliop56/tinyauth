import { Form, FormControl, FormField, FormItem } from "../ui/form";
import { Input } from "../ui/input";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { totpSchema, TotpSchema } from "@/schemas/totp-schema";
import { useTranslation } from "react-i18next";
import { useRef } from "react";
import z from "zod";

interface Props {
  formId: string;
  onSubmit: (code: TotpSchema) => void;
}

export const TotpForm = (props: Props) => {
  const { formId, onSubmit } = props;
  const { t } = useTranslation();
  const autoSubmittedRef = useRef(false);

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const form = useForm<TotpSchema>({
    resolver: zodResolver(totpSchema),
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, "").slice(0, 6);
    form.setValue("code", value, { shouldDirty: true, shouldValidate: false });
    if (value.length === 6 && !autoSubmittedRef.current) {
      autoSubmittedRef.current = true;
      form.handleSubmit(onSubmit)();
      return;
    }
    autoSubmittedRef.current = false;
  };

  // Note: This is not the best UX, ideally we would want https://github.com/guilhermerodz/input-otp
  // but some password managers cannot autofill the inputs (see #92) so, simple input it is
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
