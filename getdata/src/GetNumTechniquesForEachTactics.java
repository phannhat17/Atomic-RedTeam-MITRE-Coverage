import org.json.JSONArray;
import java.io.FileWriter;
import org.json.JSONObject;
import org.json.JSONException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class GetNumTechniquesForEachTactics {
    public static void main(String[] args) {
        try {
            String[] tacticsList =  {"collection","command-and-control","credential-access","defense-evasion","discovery","execution","exfiltration","impact","initial-access","lateral-movement","persistence","privilege-escalation","reconnaissance","resource-development"};

            String[] techniqueList = {"enterprise-attack","ics-attack","mobile-attack"};

            for (String technique : techniqueList) {
                // Read JSON file as a string
                String jsonStr = new String(Files.readAllBytes(Paths.get("./mitre-attack/"+technique+".json")));
                
                // Parse the JSON string
                JSONObject bundleJson = new JSONObject(jsonStr);

                // Get the "objects" array from the bundle
                JSONArray objects = bundleJson.getJSONArray("objects");
                int cnt =0;
                FileWriter myWriter = new FileWriter("./mitre-attack/"+technique+".txt");
                for (String tac : tacticsList) {
                
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
                                                if (phaseName != null && phaseName.equals(tac)) {
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
                                                        // System.out.println("ID: " + externalId);
                                                        cnt++;
                                                    }
                                                }
                                            }
                                        }             
                                    }
                        }
                        myWriter.write("- "+ tac+ ": " + cnt + "\n");
                        if (cnt > 0) {
                            cnt =0;
                        }
                    }
                
                myWriter.close();
                // System.out.println("Number of Techniques: " + cnt);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}