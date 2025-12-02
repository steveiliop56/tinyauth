import { Form, FormControl, FormField, FormItem } from "../ui/form";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from "../ui/input-otp";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { totpSchema, TotpSchema } from "@/schemas/totp-schema";
import { useTranslation } from "react-i18next";
import z from "zod";

interface Props {
  formId: string;
  onSubmit: (code: TotpSchema) => void;
  loading?: boolean;
}

export const TotpForm = (props: Props) => {
  const { formId, onSubmit, loading } = props;
  const { t } = useTranslation();

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const form = useForm<TotpSchema>({
    resolver: zodResolver(totpSchema),
  });

  return (
    <Form {...form}>
      <form id={formId} onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          control={form.control}
          name="code"
          render={({ field }) => (
            <FormItem>
              <FormControl>
                <InputOTP
                  maxLength={6}
                  disabled={loading}
                  {...field}
                  autoComplete="one-time-code"
                  autoFocus
                >
                  <InputOTPGroup>
                    <InputOTPSlot index={0} />
                    <InputOTPSlot index={1} />
                    <InputOTPSlot index={2} />
                  </InputOTPGroup>
                  <InputOTPSeparator />
                  <InputOTPGroup>
                    <InputOTPSlot index={3} />
                    <InputOTPSlot index={4} />
                    <InputOTPSlot index={5} />
                  </InputOTPGroup>
                </InputOTP>
              </FormControl>
            </FormItem>
          )}
        />
      </form>
    </Form>
  );
};
