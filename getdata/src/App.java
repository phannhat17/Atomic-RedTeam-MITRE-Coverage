import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.nio.file.Files;
import java.nio.file.Paths;

public class App {
    public static void main(String[] args) {
        try {
            // Read JSON file as a string
            String jsonStr = new String(Files.readAllBytes(Paths.get("./mitre-attack/mobile-attack.json")));

            // Parse the JSON string
            JSONObject bundleJson = new JSONObject(jsonStr);

            // Get the "objects" array from the bundle
            JSONArray objects = bundleJson.getJSONArray("objects");

            int cnt =0;
            for (int i = 0; i < objects.length(); i++) {
                
                JSONObject obj = objects.getJSONObject(i);

                if (obj.getString("type").equals("attack-pattern")
                        && obj.optBoolean("x_mitre_is_subtechnique") == false
                        && obj.optBoolean("x_mitre_deprecated", false) == false
                        && obj.optBoolean("revoked", false) == false) {
                    
                            JSONArray externalReferences = obj.getJSONArray("external_references");
                            JSONArray killChainPhases = obj.optJSONArray("kill_chain_phases");
                            boolean hasCollectionPhase = false;
        
                            if (killChainPhases != null) {
                                for (int j = 0; j < killChainPhases.length(); j++) {
                                    JSONObject phase = killChainPhases.getJSONObject(j);
                                    String phaseName = phase.optString("phase_name");
                                    if (phaseName != null && phaseName.equals("persistence")) {
                                        hasCollectionPhase = true;
                                        break;
                                    }
                                }
                            }

                            if (hasCollectionPhase) {
                                for (int j = 0; j < externalReferences.length(); j++) {
                                    JSONObject ref = externalReferences.getJSONObject(j);
                                    if (ref.has("external_id")) {
                                        String externalId = ref.getString("external_id");
                                        if (externalId.startsWith("T")) {
                                            System.out.println("ID: " + externalId);
                                            cnt++;
                                        }
        
                                    }
                                }
                            }                
                }
            }
            System.out.println("Number of Techniques: " + cnt);
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}