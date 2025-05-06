package com.example.gradeassignmnettwo;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;


import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import java.util.HashMap;
import java.util.Map;


public class MainActivity extends AppCompatActivity {
    EditText editTextUsername, editTextPassword;
    Button buttonLogin, buttonSignup;

    String URL_LOGIN = "http://10.0.2.2/inclass/login.php";
    String URL_SIGNUP = "http://10.0.2.2/inclass/signup.php";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        editTextUsername = findViewById(R.id.editTextUsername);
        editTextPassword = findViewById(R.id.editTextPassword);
        buttonLogin = findViewById(R.id.buttonLogin);
        buttonSignup = findViewById(R.id.buttonSignup);

        buttonLogin.setOnClickListener(v -> {
            String username = editTextUsername.getText().toString().trim();
            String password = editTextPassword.getText().toString().trim();

            StringRequest stringRequest = new StringRequest(Request.Method.POST, URL_LOGIN,
                    response -> {
                        if (response.trim().equals("success")) {
                            Intent intent = new Intent(MainActivity.this, WelcomeActivity.class);
                            intent.putExtra("username", username);
                            startActivity(intent);
                        } else {
                            Toast.makeText(MainActivity.this, "Invalid credentials", Toast.LENGTH_SHORT).show();
                        }
                    },
                    error -> Toast.makeText(MainActivity.this, "Network Error", Toast.LENGTH_SHORT).show()
            ) {
                @Override
                protected Map<String, String> getParams() {
                    Map<String, String> map = new HashMap<>();
                    map.put("username", username);
                    map.put("password", password);
                    return map;
                }
            };

            RequestQueue queue = Volley.newRequestQueue(MainActivity.this);
            queue.add(stringRequest);
        });

        buttonSignup.setOnClickListener(v -> {
            String username = editTextUsername.getText().toString().trim();
            String password = editTextPassword.getText().toString().trim();

            StringRequest stringRequest = new StringRequest(Request.Method.POST, URL_SIGNUP,
                    response -> {
                        if (response.trim().equals("success")) {
                            Toast.makeText(MainActivity.this, "Signup successful", Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(MainActivity.this, "Signup failed", Toast.LENGTH_SHORT).show();
                        }
                    },
                    error -> Toast.makeText(MainActivity.this, "Network Error", Toast.LENGTH_SHORT).show()
            ) {
                @Override
                protected Map<String, String> getParams() {
                    Map<String, String> map = new HashMap<>();
                    map.put("username", username);
                    map.put("password", password);
                    return map;
                }
            };

            RequestQueue queue = Volley.newRequestQueue(MainActivity.this);
            queue.add(stringRequest);
        });
    }
    }
