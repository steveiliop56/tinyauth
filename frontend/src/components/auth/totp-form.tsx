import { z } from "zod";
import { Form, FormControl, FormField, FormItem } from "../ui/form";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
  InputOTPSlot,
} from "../ui/input-otp";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";

interface Props {
  formId: string;
  onSubmit: (code: FormValues) => void;
}

const schema = z.object({
  code: z.string(),
});

export type FormValues = z.infer<typeof schema>;

export const TotpForm = (props: Props) => {
  const { formId, onSubmit } = props;

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
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
                <InputOTP maxLength={6} {...field}>
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
