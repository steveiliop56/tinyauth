import { Button, Paper, PasswordInput, TextInput, Title } from "@mantine/core";
import { useForm, zodResolver } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { z } from "zod";
import { useUserContext } from "../context/user-context";
import { Navigate } from "react-router";
import { Layout } from "../components/layouts/layout";

export const LoginPage = () => {
  const queryString = window.location.search;
  const params = new URLSearchParams(queryString);
  const redirectUri = params.get("redirect_uri");

  const { isLoggedIn } = useUserContext();

  if (isLoggedIn) {
    return <Navigate to="/logout" />;
  }

  const schema = z.object({
    email: z.string().email({ message: "Invalid email" }),
    password: z.string(),
  });

  type FormValues = z.infer<typeof schema>;

  const form = useForm({
    mode: "uncontrolled",
    initialValues: {
      email: "",
      password: "",
    },
    validate: zodResolver(schema),
  });

  const loginMutation = useMutation({
    mutationFn: (login: FormValues) => {
      return axios.post("/api/login", login);
    },
    onError: () => {
      notifications.show({
        title: "Failed to login",
        message: "Check your email and password",
        color: "red",
      });
    },
    onSuccess: () => {
      notifications.show({
        title: "Logged in",
        message: "Welcome back!",
        color: "green",
      });
      setTimeout(() => {
        window.location.replace(`/continue?redirect_uri=${redirectUri}`);
      });
    },
  });

  const handleSubmit = (values: FormValues) => {
    loginMutation.mutate(values);
  };

  return (
    <Layout>
      <Title ta="center">Welcome back!</Title>
      <Paper shadow="md" p={30} mt={30} radius="md" withBorder>
        <form onSubmit={form.onSubmit(handleSubmit)}>
          <TextInput
            label="Email"
            placeholder="you@example.com"
            required
            disabled={loginMutation.isLoading}
            key={form.key("email")}
            {...form.getInputProps("email")}
          />
          <PasswordInput
            label="Password"
            placeholder="password"
            required
            mt="md"
            disabled={loginMutation.isLoading}
            key={form.key("password")}
            {...form.getInputProps("password")}
          />
          <Button
            fullWidth
            mt="xl"
            type="submit"
            loading={loginMutation.isLoading}
          >
            Sign in
          </Button>
        </form>
      </Paper>
    </Layout>
  );
};
