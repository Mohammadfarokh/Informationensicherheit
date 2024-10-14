package com.example.cryptography;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class JSONObject{
    public static ObjectNode toJSONObject() {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.createObjectNode()
                .put("algorithm", "AES")
                .put("keyLength", 256)
                .put("paddingMethod",25 )
                .put("blockMode", 23)
                .put("ciphertext", "");
    }
}
